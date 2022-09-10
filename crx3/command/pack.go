package command

import (
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	crx3 "github.com/tio-dev/go-crx3"
)

type packOpts struct {
	PrivateKey string
	Outfile    string
}

func (o packOpts) HasPem() bool {
	return len(o.PrivateKey) > 0
}

func newPackCmd() *cobra.Command {
	var opts packOpts
	cmd := &cobra.Command{
		Use:   "pack [extension]",
		Short: "Pack zip file or unzipped directory into a crx extension",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("infile is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			unpacked := args[0]
			var pk ed25519.PrivateKey
			if opts.HasPem() {
				pk, err = crx3.LoadPrivateKey(opts.PrivateKey)
				if err != nil {
					return err
				}
				pub := pk.Public()
				fmt.Printf("USING PK: %s\n", base32.StdEncoding.EncodeToString([]byte(pub.(ed25519.PublicKey))))
			}
			return crx3.Pack(unpacked, opts.Outfile, pk)
		},
	}

	cmd.Flags().StringVarP(&opts.PrivateKey, "pem", "p", "", "load private key")
	cmd.Flags().StringVarP(&opts.Outfile, "outfile", "o", "", "save to file")

	return cmd
}
