// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Command nitro verifies an AWS Nitro Enclave attestation document and writes the
// suite's durable outputs: .nitro/attestation.json (read by attest as
// context.platform.*) and, optionally, the attest:nitro-attested IAM tag (checked
// by ground's SCP).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/spf13/cobra"

	"github.com/provabl/nitro/internal/attestor"
	"github.com/provabl/nitro/internal/nsm"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "nitro",
		Short:   "AWS Nitro Enclave attestation producer for the Provabl suite",
		Version: version,
	}
	cmd.AddCommand(attestCmd())
	return cmd
}

func attestCmd() *cobra.Command {
	var (
		docPath      string
		useDevice    bool
		roleARN      string
		nitroDir     string
		region       string
		expectedPCR0 string
		expectedPCR8 string
	)
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Verify an attestation document and write .nitro/attestation.json",
		Long: `Verify an AWS Nitro Enclave attestation document, writing the lowered
result to .nitro/attestation.json for attest's context.platform.* and,
when --role-arn is given and the document is attested, the
attest:nitro-attested IAM tag that ground's SCP checks.

Off-enclave, supply a captured document with --doc. A document minted for a
different challenge verifies its signature and PCRs but reports
nonce_verified=false (it is not fresh for this run).

Inside a Nitro enclave, use --device to read a fresh document directly from
/dev/nsm (the binary must be built with -tags nsm). The live device read binds
this run's challenge natively, so nonce_verified=true.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (docPath == "") == !useDevice {
				return fmt.Errorf("specify exactly one of --doc (a captured document) or --device (read /dev/nsm inside an enclave)")
			}
			ctx := context.Background()

			var tagger attestor.IAMTagger
			if roleARN != "" {
				t, err := newIAMTagger(ctx, region)
				if err != nil {
					return err
				}
				tagger = t
			}

			subject := docPath
			var a *attestor.Attestor
			if useDevice {
				subject = "/dev/nsm"
				a = attestor.New(nsm.DeviceSource{}, nsm.NewVerifier(), tagger, nitroDir)
			} else {
				a = attestor.New(nsm.FileSource{Path: docPath}, nsm.NewVerifier(), tagger, nitroDir)
			}

			expected := map[string]string{}
			if expectedPCR0 != "" {
				expected["0"] = expectedPCR0
			}
			if expectedPCR8 != "" {
				expected["8"] = expectedPCR8
			}

			res, err := a.Attest(ctx, roleARN, expected)
			if err != nil {
				return err
			}

			p := res.Platform
			fmt.Printf("Attestation: %s\n\n", subject)
			fmt.Printf("  context.platform.nitro_attested  = %v\n", p.NitroAttested)
			fmt.Printf("  context.platform.module_id       = %s\n", p.ModuleID)
			fmt.Printf("  context.platform.nonce_verified  = %v\n", p.NonceVerified)
			fmt.Printf("  context.platform.signature_valid = %v\n", p.SignatureValid)
			fmt.Printf("  context.platform.pcr0            = %s\n", p.PCR0)
			fmt.Printf("\n✓ Written to %s\n", res.WrotePath)
			if res.TaggedRole != "" {
				fmt.Printf("✓ Tagged role %s: %s=true\n", res.TaggedRole, attestor.TagNitroAttested)
			}
			if !p.NitroAttested {
				fmt.Printf("\n✗ Not attested: %s\n", res.Reason)
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&docPath, "doc", "", "path to a captured attestation document (CBOR/COSE_Sign1)")
	cmd.Flags().BoolVar(&useDevice, "device", false, "read a fresh document from /dev/nsm (inside a Nitro enclave; requires -tags nsm)")
	cmd.Flags().StringVar(&roleARN, "role-arn", "", "IAM role ARN to tag attest:nitro-attested=true when attested")
	cmd.Flags().StringVar(&nitroDir, "nitro-dir", ".nitro", "output directory for attestation.json")
	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region for IAM tagging")
	cmd.Flags().StringVar(&expectedPCR0, "expected-pcr0", "", "require this PCR0 (enclave image) hex value")
	cmd.Flags().StringVar(&expectedPCR8, "expected-pcr8", "", "require this PCR8 (signing cert) hex value")
	return cmd
}

// awsIAMTagger adapts the AWS IAM client to attestor.IAMTagger.
type awsIAMTagger struct{ client *iam.Client }

func newIAMTagger(ctx context.Context, region string) (*awsIAMTagger, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &awsIAMTagger{client: iam.NewFromConfig(cfg)}, nil
}

func (t *awsIAMTagger) TagRole(ctx context.Context, roleName string, tags map[string]string) error {
	in := &iam.TagRoleInput{RoleName: aws.String(roleName)}
	for k, v := range tags {
		in.Tags = append(in.Tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	_, err := t.client.TagRole(ctx, in)
	return err
}
