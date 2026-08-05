ALTER TABLE provider_join_challenges
    ADD COLUMN IF NOT EXISTS agent_endpoint text;

ALTER TABLE providers
    ADD COLUMN IF NOT EXISTS agent_endpoint text;
