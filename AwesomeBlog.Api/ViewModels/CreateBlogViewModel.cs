using System;
using FluentValidation;

namespace AwesomeBlog.Api.ViewModels
{
    public class CreateBlogViewModel
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public DateTime CreatedOn { get; set; }
        public AuthorViewModel Author { get; set; }
    }

    public class CreateBlogViewModelValidator : AbstractValidator<CreateBlogViewModel>
    {
        public CreateBlogViewModelValidator()
        {
            RuleFor(x => x.Id).NotEmpty();
            RuleFor(x => x.Name).NotEmpty().MinimumLength(5);
            RuleFor(x => x.CreatedOn).LessThan(DateTime.Now);
            RuleFor(x => x.Author).SetValidator(new AuthorViewModelValidator());
        }
    }
}