set -e -u
set -x

export GOPROXY=https://artifactorycn.netcracker.com/pd.saas-release.golang.group,https://artifactorycn.netcracker.com/pd.sandbox-staging.go.group
export GOSUMDB=off

echo "build"