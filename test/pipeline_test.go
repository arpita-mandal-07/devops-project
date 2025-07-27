package test

import (
	"os"
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestTerraformPipeline(t *testing.T) {
  t.Parallel()

  tf := &terraform.Options{
    TerraformDir: "../terraform", // Adjust path as per your directory
    VarFiles: []string{"terraform.tfvars"}, // Path to your variable file
    TerraformBinary: "terraform",
  }

  defer func() {
    if os.Getenv("SKIP_DESTROY") != "true" {
      terraform.Destroy(t, tf)             // Cleanup after test if not skipped
    }
  }()

  terraform.InitAndApply(t, tf)             
  
  pipelineName := terraform.Output(t, tf, "pipeline_name")
  assert.NotEmpty(t, pipelineName)
}
