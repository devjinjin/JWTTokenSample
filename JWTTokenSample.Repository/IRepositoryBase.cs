using System.Linq.Expressions;

namespace JWTTokenSample.Repository
{
    public interface IRepositoryBase<T>
    {
        IQueryable<T> FindAll(bool trackChanges);

        IQueryable<T> FindAll();

        T? FindById(string id);

        T? FindById(int id);

        T? FindById(long id);

        IQueryable<T> FindByCondition(Expression<Func<T, bool>> expression);

        void Create(T entity);

        void Update(T entity);

        void Delete(T entity);

    }
}
