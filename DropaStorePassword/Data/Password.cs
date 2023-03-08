using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace DropaStorePassword.Data
{
    public class Password
    {
        [Key]
        public long ID { get; set; }
        public string? UserName { get; set; } = string.Empty;
        public string? PasswordHash { get; set; } = string.Empty;

        public DateTime CreateTime { get; set; } = DateTime.Now;

        [JsonIgnore]
        public virtual AppUser? AppUser { get; set; }
        [JsonIgnore]
        public string? AppUserId { get; set; }
    }
}