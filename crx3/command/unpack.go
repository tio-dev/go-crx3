package command

import (
	"errors"

	"github.com/spf13/cobra"
	crx3 "github.com/tio-dev/go-crx3"
)

type unpackOpts struct {
	PublicKeyPEM string
	PublicKey    string
	OutDirectory string
}

func (o unpackOpts) HasPem() bool {
	return len(o.PublicKeyPEM) > 0
}
func (o unpackOpts) HasOut() bool {
	return len(o.OutDirectory) > 0
}
func (o unpackOpts) HasKey() bool {
	return len(o.PublicKey) > 0
}

func newUnpackCmd() *cobra.Command {
	var opts unpackOpts
	cmd := &cobra.Command{
		Use:   "unpack [extension.crx]",
		Short: "Unpack chrome extension into current directory",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("extension is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			infile := args[0]
			var out *string
			if opts.HasOut() {
				out = &opts.OutDirectory
			}
			var isPEM bool
			var key *string
			if opts.HasPem() {
				key = &opts.PublicKeyPEM
				isPEM = true
			} else if opts.HasKey() {
				key = &opts.PublicKey
				isPEM = false
			}

			return crx3.Unpack(infile, out, key, isPEM)
		},
	}
	cmd.Flags().StringVarP(&opts.PublicKey, "key", "k", "", "public key base32 for signature verification")
	cmd.Flags().StringVarP(&opts.PublicKeyPEM, "pem", "p", "", "public key PEM file for signature verification")
	cmd.Flags().StringVarP(&opts.OutDirectory, "out", "o", "", "unpack to specified directory")

	return cmd
}
