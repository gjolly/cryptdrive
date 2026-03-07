-- Migration: 002_add_subscription_tier
-- Description: Add subscription_tier column to users table
-- Created: 2026-03-07

ALTER TABLE users ADD COLUMN subscription_tier INTEGER NOT NULL DEFAULT 0;
