{-# LANGUAGE FlexibleContexts #-}
module IAM.Server.DB ( DB(..) ) where

import Control.Monad.IO.Class
import Control.Monad.Except
import Data.Text

import IAM.Error
import IAM.Group
import IAM.GroupPolicy
import IAM.GroupIdentifier
import IAM.Ip
import IAM.ListResponse
import IAM.Membership
import IAM.Policy
import IAM.User
import IAM.UserPolicy
import IAM.UserIdentifier
import IAM.Range
import IAM.Session
import IAM.Sort


class DB db where

  -- | getUser returns a user from the database by its identifier.
  getUser :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> m User

  -- | getUserId returns a user id by its identifier.
  getUserId :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> m UserId

  -- | listUsers returns a list of all users in the database.
  listUsers :: (MonadIO m, MonadError Error m) =>
    db -> Range -> SortUsersBy -> SortOrder -> m (ListResponse UserIdentifier)

  -- | listUsersBySearchTerm returns a list of all users in the database
  -- | that match a search term.
  listUsersBySearchTerm :: (MonadIO m, MonadError Error m) =>
    db -> Text -> Range -> SortUsersBy -> SortOrder -> m (ListResponse UserIdentifier)

  -- | createUser adds a new user to the database.
  createUser :: (MonadIO m, MonadError Error m) =>
    db -> User -> m User

  -- | deleteUser removes a user from the database by its email.
  deleteUser :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> m User

  -- | getGroup returns a group from the database by its name.
  getGroup :: (MonadIO m, MonadError Error m) =>
    db -> GroupIdentifier -> m Group

  -- | listGroups returns a list of all groups in the database.
  listGroups :: (MonadIO m, MonadError Error m) =>
    db -> Range -> m (ListResponse GroupIdentifier)

  listGroupsBySearchTerm :: (MonadIO m, MonadError Error m) =>
    db -> Text -> Range -> m (ListResponse GroupIdentifier)

  -- | createGroup adds a new group to the database.
  createGroup :: (MonadIO m, MonadError Error m) =>
    db -> Group -> m Group

  -- | deleteGroup removes a group from the database by its name.
  deleteGroup :: (MonadIO m, MonadError Error m) =>
    db -> GroupIdentifier -> m Group

  -- | getPolicy returns a policy from the database by its id.
  getPolicy :: (MonadIO m, MonadError Error m) =>
    db -> PolicyIdentifier -> m Policy

  -- | listPolicyIds returns a list of all policies in the database.
  listPolicyIds :: (MonadIO m, MonadError Error m) =>
    db -> Range -> m (ListResponse PolicyIdentifier)

  -- | listPolicyIdsBySearchTerm returns a list of all policies in the
  -- | database that match a search term.
  listPolicyIdsBySearchTerm :: (MonadIO m, MonadError Error m) =>
    db -> Text -> Range -> m (ListResponse PolicyIdentifier)

  -- | listPoliciesForUser returns a list of all policies attached
  -- | to a user and its groups.
  listPoliciesForUser :: (MonadIO m, MonadError Error m) =>
    db -> UserId -> Text -> m [Policy]

  -- | createPolicy adds a new policy to the database.
  createPolicy :: (MonadIO m, MonadError Error m) =>
    db -> Policy -> m Policy

  -- | updatePolicy updates an existing policy in the database.
  updatePolicy :: (MonadIO m, MonadError Error m) =>
    db -> Policy -> m Policy

  -- | deletePolicy removes a policy from the database by its name.
  deletePolicy :: (MonadIO m, MonadError Error m) =>
    db -> PolicyIdentifier -> m Policy

  -- | createMembership adds a user to a group.
  createMembership :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> GroupIdentifier -> m Membership

  -- | deleteMembership removes a user from a group.
  deleteMembership :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> GroupIdentifier -> m Membership

  -- | createUserPolicyAttachment attaches a policy to a user.
  createUserPolicyAttachment :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> PolicyIdentifier -> m UserPolicyAttachment

  -- | deleteUserPolicyAttachment detaches a policy from a user.
  deleteUserPolicyAttachment :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> PolicyIdentifier -> m UserPolicyAttachment

  -- | createGroupPolicyAttachment attaches a policy to a group.
  createGroupPolicyAttachment :: (MonadIO m, MonadError Error m) =>
    db -> GroupIdentifier -> PolicyIdentifier -> m GroupPolicyAttachment

  -- | deleteGroupPolicyAttachment detaches a policy from a group.
  deleteGroupPolicyAttachment :: (MonadIO m, MonadError Error m) =>
    db -> GroupIdentifier -> PolicyIdentifier -> m GroupPolicyAttachment

  -- | createSession adds a new session to the database.
  createSession :: (MonadIO m, MonadError Error m) =>
    db -> IpAddr -> UserId -> m CreateSession

  -- | getSessionById returns a session from the database by its id.
  getSessionById :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> SessionId -> m Session

  -- | getSessionByToken returns a session from the database by its token.
  getSessionByToken :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> Text -> m Session

  -- | refreshSession updates the expiration time of a session.
  refreshSession :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> SessionId -> m Session

  -- | deleteSession removes a session from the database by its id.
  deleteSession :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> SessionId -> m Session

  -- | listUserSessions returns a list of all sessions for a user.
  listUserSessions :: (MonadIO m, MonadError Error m) =>
    db -> UserIdentifier -> Range -> m (ListResponse Session)
