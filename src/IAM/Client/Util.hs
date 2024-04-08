module IAM.Client.Util
  ( printClientError
  , handleClientError
  , serverUrl
  ) where

import Data.ByteString.Lazy (toStrict)
import Data.Text
import Data.Text.Encoding
import Network.HTTP.Types.Status
import Servant.Client
import System.Exit

import IAM.Config


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
      putStrLn $ "Not found: " ++ rBody
    s | s == status500 ->
      putStrLn "Internal server error"
    s | s == status502 ->
      putStrLn "Bad gateway"
    s | s == status503 ->
      putStrLn "Service unavailable"
    _anyOtherStatus ->
      putStrLn "Unknown failure"
  where
    rBody = unpack $ decodeUtf8 $ toStrict $ responseBody response
printClientError (DecodeFailure _ _) =
  putStrLn "Error decoding response"
printClientError (UnsupportedContentType _ _) =
  putStrLn "Unsupported content type"
printClientError (InvalidContentTypeHeader _) =
  putStrLn "Invalid content type header"
printClientError (ConnectionError _) =
  putStrLn "Connection error"


serverUrl :: IO BaseUrl
serverUrl = parseBaseUrl =<< configURL
