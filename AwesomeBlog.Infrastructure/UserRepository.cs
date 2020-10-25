using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Threading.Tasks;
using AwesomeBlog.Model;
using MongoDB.Driver;
using MongoDB.Driver.Linq;

namespace AwesomeBlog.Infrastructure
{
    public class UserRepository
    {
        private readonly DatabaseContext _databaseContext;

        public UserRepository(DatabaseContext databaseContext)
        {
            _databaseContext = databaseContext;
        }
        
        public async Task Create(User user)
        {
            await _databaseContext
                .GetCollection<User>()
                .InsertOneAsync(user);
        }
    }
}