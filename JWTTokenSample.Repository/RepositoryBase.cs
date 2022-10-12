using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace JWTTokenSample.Repository
{
    public abstract class RepositoryBase<T> : IRepositoryBase<T> where T : class
    {
        protected ApplicationDbContext RepositoryContext { get; set; }
        public RepositoryBase(ApplicationDbContext repositoryContext)
        {
            this.RepositoryContext = repositoryContext;
        }
        public IQueryable<T> FindAll()
        {
            return this.RepositoryContext.Set<T>().AsNoTracking();
        }

        public IQueryable<T> FindAll(bool trackChanges)
        {
            if (!trackChanges)
            {
                return this.RepositoryContext.Set<T>().AsNoTracking(); //AsNoTracking 차이점 알기
            }
            else
            {
                return RepositoryContext.Set<T>();
            }
        }

        public IQueryable<T> FindByCondition(Expression<Func<T, bool>> expression)
        {
            return this.RepositoryContext.Set<T>().Where(expression).AsNoTracking(); //AsNoTracking 차이점 알기
        }

        public IQueryable<T> FindByCondition(Expression<Func<T, bool>> expression, bool trackChanges)
        {
            if (!trackChanges)
            {
                return this.RepositoryContext.Set<T>()
                .Where(expression).AsNoTracking(); //AsNoTracking 차이점 알기
            }
            else
            {
                return this.RepositoryContext.Set<T>().Where(expression);
            }
        }
        public void Create(T entity)
        {
            this.RepositoryContext.Set<T>().Add(entity);
        }
        public void Update(T entity)
        {
            this.RepositoryContext.Set<T>().Update(entity);
        }
        public void Delete(T entity)
        {
            this.RepositoryContext.Set<T>().Remove(entity);
        }

        public T? FindById(string id)
        {
            return this.RepositoryContext.Set<T>().Find(id);
        }

        public T? FindById(int id)
        {
            return this.RepositoryContext.Set<T>().Find(id);
        }

        public T? FindById(long id)
        {
            return this.RepositoryContext.Set<T>().Find(id);
        }

    }
}
