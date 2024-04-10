module IAM.Range
  ( Range(..)
  ) where


data Range = Range
  { rangeOffset :: !Int
  , rangeLimit :: !(Maybe Int)
  } deriving (Eq, Show)
