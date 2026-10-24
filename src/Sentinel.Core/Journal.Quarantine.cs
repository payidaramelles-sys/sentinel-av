using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Sentinel.Core;

public sealed partial class Journal
{
    public void SaveQuarantine(QuarantineEntry e)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO quarantine(id,orig_path,sha256,size,detected_by,verdict,created_at,restored_at)
                VALUES($id,$o,$h,$s,$d,$v,$c,NULL)
                """;
            cmd.Parameters.AddWithValue("$id", e.Id);
            cmd.Parameters.AddWithValue("$o", e.OriginalPath);
            cmd.Parameters.AddWithValue("$h", e.Sha256);
            cmd.Parameters.AddWithValue("$s", e.Size);
            cmd.Parameters.AddWithValue("$d", e.DetectedBy);
            cmd.Parameters.AddWithValue("$v", (int)e.Verdict);
            cmd.Parameters.AddWithValue("$c", e.CreatedAt.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public QuarantineEntry? GetQuarantine(string id)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                SELECT id,orig_path,sha256,size,detected_by,verdict,created_at,restored_at
                FROM quarantine WHERE id=$id
                """;
            cmd.Parameters.AddWithValue("$id", id);
            using var r = cmd.ExecuteReader();
            return r.Read() ? ReadQuarantine(r) : null;
        }
    }

    public List<QuarantineEntry> ListQuarantine()
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = """
                SELECT id,orig_path,sha256,size,detected_by,verdict,created_at,restored_at
                FROM quarantine ORDER BY created_at DESC
                """;
            using var r = cmd.ExecuteReader();
            var list = new List<QuarantineEntry>();
            while (r.Read()) list.Add(ReadQuarantine(r));
            return list;
        }
    }

    private static QuarantineEntry ReadQuarantine(SqliteDataReader r) => new()
    {
        Id = r.GetString(0),
        OriginalPath = r.GetString(1),
        Sha256 = r.GetString(2),
        Size = r.GetInt64(3),
        DetectedBy = r.IsDBNull(4) ? "" : r.GetString(4),
        Verdict = (Verdict)r.GetInt32(5),
        CreatedAt = DateTimeOffset.Parse(r.GetString(6), CultureInfo.InvariantCulture),
        RestoredAt = r.IsDBNull(7) ? null : DateTimeOffset.Parse(r.GetString(7), CultureInfo.InvariantCulture)
    };

    public void MarkQuarantineRestored(string id)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "UPDATE quarantine SET restored_at=$r WHERE id=$id";
            cmd.Parameters.AddWithValue("$r", DateTimeOffset.Now.ToString("O"));
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    public void DeleteQuarantine(string id)
    {
        lock (_gate)
        {
            using var cn = Open();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = "DELETE FROM quarantine WHERE id=$id";
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }
}
