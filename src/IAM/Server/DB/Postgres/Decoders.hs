module IAM.Server.DB.Postgres.Decoders
  ( module IAM.Server.DB.Postgres.Decoders
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.Text
import Data.Time.Clock
import Data.UUID (UUID)
import qualified Hasql.Decoders as D


import IAM.Ip
import IAM.Login
import IAM.Session
import IAM.UserIdentifier
import IAM.UserPublicKey


loginResponseDecoder :: D.Row LoginResponse
loginResponseDecoder =
  (constructLoginResponse .
  LoginRequestId <$> D.column (D.nonNullable D.uuid)) <*>
  (UserUUID <$> D.column (D.nonNullable D.uuid)) <*>
  (PublicKey <$> D.column (D.nonNullable D.bytea)) <*>
  D.column (D.nonNullable D.text) <*>
  D.column (D.nullable D.uuid) <*>
  (IpAddr <$> D.column (D.nonNullable D.inet)) <*>
  D.column (D.nonNullable D.timestamptz) <*>
  D.column (D.nonNullable D.bool) <*>
  D.column (D.nonNullable D.bool)


constructLoginResponse ::
  LoginRequestId -> UserId -> PublicKey -> Text -> Maybe UUID -> IpAddr ->
    UTCTime -> Bool -> Bool -> LoginResponse
constructLoginResponse lid uid pk desc sid ip ex g d = LoginResponse
  { loginResponseIp = ip
  , loginResponseRequest = lid
  , loginResponseUserId = uid
  , loginResponsePublicKey = UserPublicKey pk desc
  , loginResponseExpires = ex
  , loginResponseSession = fmap SessionUUID sid
  , loginResponseStatus = status g d
  }
  where
    status True _ = LoginRequestGranted
    status _ True = LoginRequestDenied
    status _ _ = LoginRequestPending
