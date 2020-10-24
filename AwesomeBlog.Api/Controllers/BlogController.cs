using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeBlog.Api.ViewModels;
using AwesomeBlog.Infrastructure;
using AwesomeBlog.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AwesomeBlog.Api.Controllers
{
    [Authorize]
    [Route("[controller]")]
    public class BlogController : ControllerBase
    {
        private readonly BlogRepository _blogRepository;

        public BlogController(BlogRepository blogRepository)
        {
            _blogRepository = blogRepository;
        }
        
        [HttpGet]
        public async Task<ActionResult<ICollection<Blog>>> Get()
        {
            return Ok(await _blogRepository.GetBlogs());
        }

        [HttpGet("{id:guid}")]
        public async Task<ActionResult<Blog>> Get(Guid id)
        {
            var blog = await _blogRepository.GetBlog(id);

            if (blog == null)
                return BadRequest();

            return blog;
        }

        [HttpPost]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult> Create([FromBody] CreateBlogViewModel blog)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            
            await _blogRepository.Create(new Blog
            (
                blog.Id,
                blog.Name,
                blog.CreatedOn,
                new Author(blog.Author.FirstName, blog.Author.LastName)
            ));

            return Created(string.Empty, blog);
        }

        [HttpPut]
        public async Task<ActionResult> Update([FromBody] Blog blog)
        {
            if (await _blogRepository.Update(blog))
                return Ok();

            return BadRequest();
        }

        [HttpDelete("{id:guid}")]
        public async Task<ActionResult> Delete(Guid id)
        {
            if (await _blogRepository.Delete(id))
                return Ok();

            return BadRequest();
        }
    }
}