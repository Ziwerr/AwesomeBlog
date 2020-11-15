using System;

namespace AwesomeBlog.Model
{
    public class User
    {
        public Guid Id { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public DateTime CreatedOn { get; set; }

        public User(Guid id, string userName, string password, DateTime? createdOn = null)
        {
            Id = id;
            UserName = userName;
            Password = password;
            CreatedOn = createdOn ?? new DateTime();
        }
    }
}