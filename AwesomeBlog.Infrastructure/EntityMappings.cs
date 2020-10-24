using AwesomeBlog.Model;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;

namespace AwesomeBlog.Infrastructure
{
    public static class EntityMappings
    {
        public static void Map()
        {
            BsonDefaults.GuidRepresentation = GuidRepresentation.Standard;
            
            BsonClassMap.RegisterClassMap<Blog>(x =>
            {
                x.AutoMap();
                x.SetIgnoreExtraElements(true);
                x.MapIdMember(y => y.Id);
            });
            
            BsonClassMap.RegisterClassMap<Author>(x =>
            {
                x.AutoMap();
                x.SetIgnoreExtraElements(true);
            });
        }
    }
}