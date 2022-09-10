package command

import (
	"errors"

	"github.com/spf13/cobra"
	crx3 "github.com/tio-dev/go-crx3"
)

type unpackOpts struct {
	PublicKey    string
	OutDirectory string
}

func (o unpackOpts) HasPem() bool {
	return len(o.PublicKey) > 0
}
func (o unpackOpts) HasOut() bool {
	return len(o.OutDirectory) > 0
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
			var pem *string
			if opts.HasPem() {
				pem = &opts.PublicKey
			}

			return crx3.Unpack(infile, out, pem)
		},
	}
	cmd.Flags().StringVarP(&opts.PublicKey, "pem", "p", "", "public key for signature verification")
	cmd.Flags().StringVarP(&opts.OutDirectory, "out", "o", "", "unpack to specified directory")

	return cmd
}
