using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Watch;

namespace Sentinel.Service;

public sealed class RuntimeHostedService : BackgroundService
{
    private readonly ILogger<RuntimeHostedService> _logger;
    private readonly SentinelPaths _paths;
    private readonly SentinelConfig _config;
    private readonly Journal _journal;
    private readonly ScanPipeline _pipeline;
    private readonly UsageStats _usage;

    public RuntimeHostedService(ILogger<RuntimeHostedService> logger)
    {
        _logger = logger;
        _paths = SentinelPaths.Resolve();
        _config = SentinelConfig.Load(_paths.ConfigPath);
        _journal = new Journal(_paths);
        var quarantine = new QuarantineService(_paths, _journal);
        _pipeline = new ScanPipeline(_paths, _config, _journal, quarantine);
        _usage = new UsageStats(_journal, _paths);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Sentinel service starting, home={Home}", _paths.Root);
        _journal.Log("service", "Sentinel service started", "info");

        var runtime = new SentinelRuntime(_paths, _config, _journal, _pipeline, _usage);
        try
        {
            await runtime.RunAsync(stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // normal stop
        }
        catch (Exception ex)
        {
            _journal.Log("service", "Fatal: " + ex, "error");
            _logger.LogError(ex, "Sentinel runtime failed");
            throw;
        }
        finally
        {
            _journal.Log("service", "Sentinel service stopped", "info");
        }
    }
}

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = "Sentinel");
        builder.Services.AddHostedService<RuntimeHostedService>();
        builder.Build().Run();
    }
}
