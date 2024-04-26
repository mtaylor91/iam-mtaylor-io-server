module IAM.Server.DB.Postgres.Encoders
  ( module IAM.Server.DB.Postgres.Encoders
  ) where

import Crypto.Sign.Ed25519 (PublicKey(..))
import Data.ByteString (ByteString)
import Data.Functor.Contravariant ((>$<))
import Data.Int (Int32)
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


userIdRangeEncoder :: E.Params (UserId, (Int32, Int32))
userIdRangeEncoder =
  (fst >$< userIdEncoder) <>
  (fst . snd >$< E.param (E.nonNullable E.int4)) <>
  (snd . snd >$< E.param (E.nonNullable E.int4))


loginIdentityEncoder :: E.Params (UserId, LoginRequestId)
loginIdentityEncoder = (fst >$< userIdEncoder) <> (snd >$< loginIdEncoder)


loginResponseEncoder :: E.Params (LoginResponse SessionId)
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

  pk :: LoginResponse SessionId -> ByteString
  pk = unPublicKey . userPublicKey . loginResponsePublicKey

  pkDesc :: LoginResponse SessionId -> Text
  pkDesc = userPublicKeyDescription . loginResponsePublicKey

  sid :: LoginResponse SessionId -> Maybe UUID
  sid = fmap unSessionId . loginResponseSession

  loginResponseGranted :: LoginResponse SessionId -> Bool
  loginResponseGranted lr = loginResponseStatus lr == LoginRequestGranted

  loginResponseDenied :: LoginResponse SessionId -> Bool
  loginResponseDenied lr = loginResponseStatus lr == LoginRequestDenied
