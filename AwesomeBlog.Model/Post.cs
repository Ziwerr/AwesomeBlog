using System;

namespace AwesomeBlog.Model
{
    public class Post
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        public DateTime CreatedOn { get; set; }

        public Post(Guid id, string title, string content, DateTime createdOn)
        {
            Id = id;
            Title = title;
            Content = content;
            CreatedOn = createdOn;
        }
    }
}