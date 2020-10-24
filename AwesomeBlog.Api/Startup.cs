using System.Globalization;
using System.Text;
using AwesomeBlog.Api.Settings;
using AwesomeBlog.Infrastructure;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace AwesomeBlog.Api
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services
                .AddControllers()
                .AddFluentValidation(x => x.RegisterValidatorsFromAssemblyContaining<Startup>());

            ValidatorOptions.Global.LanguageManager.Culture = new CultureInfo("pl");

            var jwtSettings = new JwtSettings();

            services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidIssuer = jwtSettings.ValidIssuer,
                        ValidAudience = jwtSettings.ValidAudience,
                        ValidateAudience = false,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret))
                    };
                });
            
            
            services.AddSingleton(provider => new DatabaseContext("mongodb://localhost:27017"));
            services.AddSingleton<BlogRepository>();
            
            services.AddSwaggerGen();
            
            EntityMappings.Map();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Awesome Blog V1");
            });
            
            app.UseHttpsRedirection();
                 
            app.UseRouting();

            app.UseAuthentication(); //Uwierzytelnianie Czy moge?
            app.UseAuthorization(); //Autoryzacja Co moge?

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }
}