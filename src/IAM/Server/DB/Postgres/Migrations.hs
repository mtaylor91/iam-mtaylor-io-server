module IAM.Server.DB.Postgres.Migrations
  ( migrate
  ) where

import Hasql.Migration
import Hasql.Pool (Pool, use)
import Hasql.Transaction.Sessions
import System.IO (hFlush, stdout)


migrate :: FilePath -> Pool -> IO ()
migrate directory db = do
  putStrLn "Migrating database..."
  hFlush stdout

  migrationCommands <- loadMigrationsFromDirectory directory
  let commands = MigrationInitialization : migrationCommands
  runMigrations db commands

  putStrLn "Database migrated."
  hFlush stdout


runMigrations :: Pool -> [MigrationCommand] -> IO ()
runMigrations _ [] = return ()
runMigrations db (command:commands) = do
  let session = transaction Serializable Write $ runMigration command
  result <- use db session
  case result of
    Left err -> do
      putStrLn $ "Migration failed: " ++ show err
      hFlush stdout
    Right _ ->
      runMigrations db commands
