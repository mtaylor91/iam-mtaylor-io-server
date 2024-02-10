{-# LANGUAGE FlexibleContexts #-}
module Lib.IAM.DB ( DB(..), DBError(..) ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Data.UUID

import Lib.IAM


data DBError
  = AlreadyExists
  | NotFound
  | InternalError
  deriving (Show, Eq)


class DB db where

  -- | getUser returns a user from the database by its email.
  getUser :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> m User

  -- | listUsers returns a list of all users in the database.
  listUsers :: (MonadIO m, MonadError DBError m) =>
    db -> m [UserId]

  -- | createUser adds a new user to the database.
  createUser :: (MonadIO m, MonadError DBError m) =>
    db -> UserPrincipal -> m UserPrincipal

  -- | deleteUser removes a user from the database by its email.
  deleteUser :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> m UserId

  -- | getGroup returns a group from the database by its name.
  getGroup :: (MonadIO m, MonadError DBError m) =>
    db -> GroupId -> m Group

  -- | listGroups returns a list of all groups in the database.
  listGroups :: (MonadIO m, MonadError DBError m) =>
    db -> m [GroupId]

  -- | createGroup adds a new group to the database.
  createGroup :: (MonadIO m, MonadError DBError m) =>
    db -> Group -> m Group

  -- | deleteGroup removes a group from the database by its name.
  deleteGroup :: (MonadIO m, MonadError DBError m) =>
    db -> GroupId -> m ()

  -- | getPolicy returns a policy from the database by its id.
  getPolicy :: (MonadIO m, MonadError DBError m) =>
    db -> UUID -> m Policy

  -- | listPolicies returns a list of all policies in the database.
  listPolicies :: (MonadIO m, MonadError DBError m) =>
    db -> m [Policy]

  -- | listPoliciesForUser returns a list of all policies attached
  -- | to a user and its groups.
  listPoliciesForUser :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> m [Policy]

  -- | createPolicy adds a new policy to the database.
  createPolicy :: (MonadIO m, MonadError DBError m) =>
    db -> Policy -> m Policy

  -- | updatePolicy updates an existing policy in the database.
  updatePolicy :: (MonadIO m, MonadError DBError m) =>
    db -> Policy -> m Policy

  -- | deletePolicy removes a policy from the database by its name.
  deletePolicy :: (MonadIO m, MonadError DBError m) =>
    db -> UUID -> m Policy

  -- | createMembership adds a user to a group.
  createMembership :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> GroupId -> m Membership

  -- | deleteMembership removes a user from a group.
  deleteMembership :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> GroupId -> m Membership

  -- | createUserPolicyAttachment attaches a policy to a user.
  createUserPolicyAttachment :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> UUID -> m UserPolicyAttachment

  -- | deleteUserPolicyAttachment detaches a policy from a user.
  deleteUserPolicyAttachment :: (MonadIO m, MonadError DBError m) =>
    db -> UserId -> UUID -> m UserPolicyAttachment

  -- | createGroupPolicyAttachment attaches a policy to a group.
  createGroupPolicyAttachment :: (MonadIO m, MonadError DBError m) =>
    db -> GroupId -> UUID -> m GroupPolicyAttachment

  -- | deleteGroupPolicyAttachment detaches a policy from a group.
  deleteGroupPolicyAttachment :: (MonadIO m, MonadError DBError m) =>
    db -> GroupId -> UUID -> m GroupPolicyAttachment
