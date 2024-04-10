module IAM.Command.Create.Group
  ( createGroup
  , createGroupOptions
  , CreateGroup(..)
  ) where

import Control.Exception
import Data.Text
import Data.UUID
import Data.UUID.V4
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Options.Applicative
import Servant.Client
import Text.Read

import IAM.Client.Auth
import IAM.Client.Util
import IAM.Group
import IAM.Identifiers
import qualified IAM.Client


data CreateGroup = CreateGroup
  { createGroupId :: !Text
  , createGroupPolicies :: ![Text]
  , createGroupUsers :: ![Text]
  } deriving (Show)


createGroup :: CreateGroup -> IO ()
createGroup createGroupInfo =
  case readMaybe (unpack $ createGroupId createGroupInfo) of
    Just uuid -> createGroupByUUID createGroupInfo uuid
    Nothing -> createGroupByName createGroupInfo $ createGroupId createGroupInfo


createGroupByName :: CreateGroup -> Text -> IO ()
createGroupByName createGroupInfo = createGroupById createGroupInfo . GroupName


createGroupByUUID :: CreateGroup -> UUID -> IO ()
createGroupByUUID createGroupInfo = createGroupById createGroupInfo . GroupId . GroupUUID


createGroupById :: CreateGroup -> GroupIdentifier -> IO ()
createGroupById createGroupInfo gident = do
  policies <- mapM translatePolicyId $ createGroupPolicies createGroupInfo
  users <- mapM translateUserId $ createGroupUsers createGroupInfo
  url <- serverUrl
  auth <- clientAuthInfo
  mgr <- newManager tlsManagerSettings { managerModifyRequest = clientAuth auth }

  gid <- case unGroupIdentifier gident of
    Right (GroupUUID uuid) -> return $ GroupUUID uuid
    Left _email -> GroupUUID <$> nextRandom

  let maybeName = unGroupIdentifierName gident
  let grp = Group gid maybeName users policies
  res <- runClientM (IAM.Client.createGroup grp) $ mkClientEnv mgr url
  case res of
    Left err -> handleClientError err
    Right _ -> return ()

  where

    translatePolicyId :: Text -> IO UUID
    translatePolicyId pid = do
      case readMaybe (unpack pid) of
        Just uuid -> return uuid
        Nothing -> throw $ userError $ "Invalid policy ID: " ++ show pid

    translateUserId :: Text -> IO UserIdentifier
    translateUserId uid = do
      case readMaybe (unpack uid) of
        Just uuid -> return $ UserId $ UserUUID uuid
        Nothing -> return $ UserEmail uid


createGroupOptions :: Parser CreateGroup
createGroupOptions = CreateGroup
  <$> argument str
    (  metavar "GROUP"
    <> help "The name or uuid of the group to create"
    )
  <*> many (strOption
    ( long "policy"
    <> short 'p'
    <> metavar "POLICY"
    <> help "The ID of a policy to attach to the group"
    ))
  <*> many (strOption
    ( long "user"
    <> short 'u'
    <> metavar "USER"
    <> help "The ID of a user to add to the group"
    ))
