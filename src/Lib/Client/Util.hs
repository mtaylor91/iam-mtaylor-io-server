module Lib.Client.Util
  ( printClientError
  , handleClientError
  ) where

import Network.HTTP.Types.Status
import Servant.Client
import System.Exit


handleClientError :: ClientError -> IO ()
handleClientError err = do
  printClientError err
  exitFailure


printClientError :: ClientError -> IO ()
printClientError (FailureResponse _ response) =
  case responseStatusCode response of
    s | s == status401 ->
      putStrLn "Unauthorized"
    s | s == status403 ->
      putStrLn "Forbidden"
    s | s == status404 ->
      putStrLn "Not found"
    _anyOtherStatus ->
      putStrLn "Unknown failure"
printClientError (DecodeFailure _ _) =
  putStrLn "Error decoding response"
printClientError (UnsupportedContentType _ _) =
  putStrLn "Unsupported content type"
printClientError (InvalidContentTypeHeader _) =
  putStrLn "Invalid content type header"
printClientError (ConnectionError _) =
  putStrLn "Connection error"
