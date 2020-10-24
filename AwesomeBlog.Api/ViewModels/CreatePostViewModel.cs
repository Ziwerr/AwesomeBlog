using System;

namespace AwesomeBlog.Api.ViewModels
{
    public class CreatePostViewModel
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        public DateTime CreatedOn { get; set; }
    }
}