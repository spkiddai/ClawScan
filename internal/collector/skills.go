package collector

import (
	"bytes"
	"encoding/json"

	"github.com/spkiddai/clawscan/internal/models"
)

type rawSkillsOutput struct {
	Skills []struct {
		Name               string `json:"name"`
		Disabled           bool   `json:"disabled"`
		BlockedByAllowlist bool   `json:"blockedByAllowlist"`
		Source             string `json:"source"`
	} `json:"skills"`
}

// CollectSkills runs `openclaw skills list --eligible --json` and returns parsed skills.
func CollectSkills() []models.Skill {
	out, err := cmdOutput("openclaw", "skills", "list", "--eligible", "--json")
	if err != nil || len(out) == 0 {
		return nil
	}

	start := bytes.IndexByte(out, '{')
	if start == -1 {
		return nil
	}

	var raw rawSkillsOutput
	if err := json.NewDecoder(bytes.NewReader(out[start:])).Decode(&raw); err != nil {
		return nil
	}

	skills := make([]models.Skill, 0, len(raw.Skills))
	for _, s := range raw.Skills {
		skills = append(skills, models.Skill{
			Name:               s.Name,
			Disabled:           s.Disabled,
			BlockedByAllowlist: s.BlockedByAllowlist,
			Source:             s.Source,
		})
	}
	return skills
}
