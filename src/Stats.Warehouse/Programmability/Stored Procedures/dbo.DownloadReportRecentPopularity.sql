﻿CREATE PROCEDURE [dbo].[DownloadReportRecentPopularity]
AS
BEGIN
	SET NOCOUNT ON;

	-- Find all packages that have had download facts added in the last 42 days
	SELECT		TOP 100 P.[PackageId]
				,SUM(ISNULL(F.[DownloadCount], 0)) AS 'Downloads'
	FROM		[dbo].[Fact_Download] AS F (NOLOCK)

	INNER JOIN	[dbo].[Dimension_Package] AS P (NOLOCK)
	ON			F.[Dimension_Package_Id] = P.[Id]

	WHERE		ISNULL(F.[Timestamp], CONVERT(DATETIME, '1900-01-01')) > CONVERT(DATE, DATEADD(day, -42, GETDATE()))
	GROUP BY	P.[PackageId]
	ORDER BY	[Downloads] DESC
END