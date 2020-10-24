using FluentValidation;

namespace AwesomeBlog.Api.ViewModels
{
    public class AuthorViewModel
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class AuthorViewModelValidator : AbstractValidator<AuthorViewModel>
    {
        public AuthorViewModelValidator()
        {
            RuleFor(x => x.LastName).NotEmpty();
        }
    }
}