using System.Data.Entity.Infrastructure;
using System.Data.SqlClient;
using System.Linq;

namespace NuGet.Jobs.Validation.PackageSigning
{
    public static class ExceptionExtensions
    {
        private const int UniqueConstraintViolationErrorCode = 2627;

        /// <summary>
        /// Check whether a <see cref="DbUpdateException"/> is due to a SQL unique constraint violation.
        /// </summary>
        /// <param name="exception">The exception to inspect.</param>
        /// <returns>Whether the exception was caused to SQL unique constraint violation.</returns>
        public static bool IsUniqueConstraintViolationException(this DbUpdateException exception)
        {
            var sqlException = exception.GetBaseException() as SqlException;

            if (sqlException != null)
            {
                return sqlException.Errors.Cast<SqlError>().Any(error => error.Number == UniqueConstraintViolationErrorCode);
            }

            return false;
        }
    }
}
