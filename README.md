# Verification & Validation of ZERA Network Wallets
This go package is used to sign and verify supported wallet types using golang on the ZERA Network

### Usecases:
- Client Signing Txns
- Interservice Verification Of Data Transasmission
- Verifying Validity Of Own Signatures

# Setup
> This is a private package which requires github authentication to fetch

Installing latest version on go project
```bash
go get -u github.com/ZeraVision/go-verify-and-sign
```

## Troubleshooting
In the event `go get` returns a 404 error:
1. Ensure that your machine is using the correct Personal Access Token or is authenticated correctly.
2. Temporarily adjust the environment variable to include the repository URL by setting `GOPRIVATE` to `github.com/ZeraVision/go-verify-and-sign`.
   #### Powershell
   ```powershell
   $env:GOPRIVATE="github.com/ZeraVision/go-verify-and-sign"
   ```
   #### ZSH Bash
   ```
   export GOPRIVATE=github.com/ZeraVision/go-verify-and-sign
   ```

# Development

## Pushing New Version to Github

1. **Determine the Tag Name:**
   First, follow the `"Version Naming Standards"` to decide on the appropriate tag name for your new version.

2. **Tag the Associated Commit:**
   To push a new version, you need to tag the   associated commit with the chosen tag name.   You can do this using the following command:
    ```bash
    git tag {tag name} 
    ```
3. **Push the Tag to GitHub:**
    Finally, push the newly created tag to GitHub:
    ```bash
    git push --tags 
    ```

### Version Naming Standards:
- Example: `"v1.12.2"`
- Expanded Format: `"v{Major Version}.{Minor Version}.{Patch Version}"`

