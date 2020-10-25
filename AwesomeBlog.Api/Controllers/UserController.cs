using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AwesomeBlog.Api.Settings;
using AwesomeBlog.Api.ViewModels;
using AwesomeBlog.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace AwesomeBlog.Api.Controllers
   {    
       
       [Route("[controller]")]
       public class UserController : Controller
       {
           private readonly UserRepository _userRepository;
           public UserController(UserRepository userRepository)
           {
               _userRepository = userRepository;
           }
           
           [HttpPost]
           public ActionResult Create([FromBody]CreateUserViewModel createUserViewModel)
           {
               // 1. Hashowanie
               // jan - password - admin -> jdasodaokdsaokcmasdoj
               // kasia - password - user -> jdasodaokdsaokcmasdoj
               // salt do hasla

               var hashed = BCrypt.Net.BCrypt.HashPassword(createUserViewModel.Password);
               
               return Ok(new
               {
                   pass = hashed,
                   ver = BCrypt.Net.BCrypt.Verify(createUserViewModel.Password, hashed)
               });

           }
           
           [HttpPost("login")]
           public ActionResult Login([FromForm] LoginViewModel loginViewModel)
           {
               //1. Sprawdzenie hasła uzytkownika
               //2. Wygenerowanie tokena

               if (loginViewModel.Password != "password")
               {
                   return BadRequest();
               }

               var jwtSettings = new JwtSettings();
               
               var tokenDescriptor = new SecurityTokenDescriptor
               {
                    Subject = new ClaimsIdentity
                    (new []
                        {
                            new Claim(JwtRegisteredClaimNames.Sub, loginViewModel.UserName),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                            //new Claim("blog","awesome"),
                            new Claim(ClaimTypes.Role,"Admin"),
                            new Claim(ClaimTypes.Role,"User"),
                        }
                    ),
                    Issuer = jwtSettings.ValidIssuer,
                    Audience = loginViewModel.Audience,
                    Expires = DateTime.UtcNow.AddSeconds(jwtSettings.LifetimeInSeconds),
                    SigningCredentials = new SigningCredentials
                    (
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret)), 
                        SecurityAlgorithms.HmacSha256Signature
                    )
               };
               
               var tokenHandler = new JwtSecurityTokenHandler();

               var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

               return Ok(new
               {
                   access_token = tokenHandler.WriteToken(token)
               });
           }
       }
   }