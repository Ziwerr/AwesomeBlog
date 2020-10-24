using System;
using System.Threading.Tasks;
using AwesomeBlog.Api.ViewModels;
using AwesomeBlog.Infrastructure;
using AwesomeBlog.Model;
using Microsoft.AspNetCore.Mvc;

namespace AwesomeBlog.Api.Controllers
{
    [Route("[controller]")]
    public class PostController : ControllerBase
    {
        private readonly BlogRepository _blogRepository;

        public PostController(BlogRepository blogRepository)
        {
            _blogRepository = blogRepository;
        }

        [HttpPost("{blogId:guid}")]
        public async Task<ActionResult> AddPost(Guid blogId, [FromBody] CreatePostViewModel createPostViewModel)
        {
            await _blogRepository.AddPost(blogId, new Post(
                createPostViewModel.Id,
                createPostViewModel.Title,
                createPostViewModel.Content,
                createPostViewModel.CreatedOn
            ));

            return Ok();
        }
        
        // [HttpDelete("{blogId:guid}")]
        // public async Task<ActionResult> DeletePost(Guid id)
        // {
        //     if (await _blogRepository.DeletePost(id))
        //         return Ok();
        //
        //     return BadRequest();
        // }
    }
}