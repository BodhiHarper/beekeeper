-- Database migration to support anonymous users with IP-based data storage
-- Run this on your existing beekeeper database

-- Add ip_address column to hives table
ALTER TABLE hives ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);

-- Make user_id nullable for anonymous users
ALTER TABLE hives ALTER COLUMN user_id DROP NOT NULL;

-- Add ip_address column to tasks table
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);

-- Make user_id nullable for anonymous users in tasks
ALTER TABLE tasks ALTER COLUMN user_id DROP NOT NULL;

-- Add indexes for faster IP-based queries
CREATE INDEX IF NOT EXISTS idx_hives_ip_address ON hives(ip_address) WHERE user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_ip_address ON tasks(ip_address) WHERE user_id IS NULL;

-- Verify the changes
SELECT 'Migration completed successfully!' as status;
