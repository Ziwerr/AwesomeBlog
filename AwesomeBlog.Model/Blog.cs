using System;
using System.Collections.Generic;
using System.Linq;

namespace AwesomeBlog.Model
{
    public class Blog
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public DateTime CreatedOn { get; set; }
        public Author Author { get; set; }
        public ICollection<Post> Posts { get; set; } = new List<Post>();

        public Blog()
        {
        }
        
        public Blog(Guid id, string name, DateTime createdOn, Author author)
        {
            Id = id;
            Name = name;
            CreatedOn = createdOn;
            Author = author;
        }

        public void AddPost(Post post)
        {
            Posts.Add(post);
        }

        public void DeletePost(Post post)
        {
            Posts.Remove(post);
        }
    }
}