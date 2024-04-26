module IAM.Server.DB.Postgres.Encoders
  ( module IAM.Server.DB.Postgres.Encoders
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.ByteString (ByteString)
import Data.Functor.Contravariant ((>$<))
import Data.Text (Text)
import Data.UUID (UUID)
import qualified Hasql.Encoders as E

import IAM.Ip
import IAM.Login
import IAM.Session
import IAM.UserIdentifier
import IAM.UserPublicKey


loginIdEncoder :: E.Params LoginRequestId
loginIdEncoder = unLoginRequestId >$< E.param (E.nonNullable E.uuid)


userIdEncoder :: E.Params UserId
userIdEncoder = unUserId >$< E.param (E.nonNullable E.uuid)


loginIdentityEncoder :: E.Params (UserId, LoginRequestId)
loginIdentityEncoder = (fst >$< userIdEncoder) <> (snd >$< loginIdEncoder)


loginResponseEncoder :: E.Params LoginResponse
loginResponseEncoder =
  ((unLoginRequestId . loginResponseRequest) >$< E.param (E.nonNullable E.uuid)) <>
  ((unUserId . loginResponseUserId) >$< E.param (E.nonNullable E.uuid)) <>
  (pk >$< E.param (E.nonNullable E.bytea)) <>
  (pkDesc >$< E.param (E.nonNullable E.text)) <>
  (sid >$< E.param (E.nullable E.uuid)) <>
  ((unIpAddr . loginResponseIp) >$< E.param (E.nonNullable E.inet)) <>
  (loginResponseExpires >$< E.param (E.nonNullable E.timestamptz)) <>
  (loginResponseGranted >$< E.param (E.nonNullable E.bool)) <>
  (loginResponseDenied >$< E.param (E.nonNullable E.bool))

  where

  pk :: LoginResponse -> ByteString
  pk = unPublicKey . userPublicKey . loginResponsePublicKey

  pkDesc :: LoginResponse -> Text
  pkDesc = userPublicKeyDescription . loginResponsePublicKey

  sid :: LoginResponse -> Maybe UUID
  sid = fmap unSessionId . loginResponseSession

  loginResponseGranted :: LoginResponse -> Bool
  loginResponseGranted lr = loginResponseStatus lr == LoginRequestGranted

  loginResponseDenied :: LoginResponse -> Bool
  loginResponseDenied lr = loginResponseStatus lr == LoginRequestDenied
