// see: https://github.com/conventional-changelog/standard-version
//
// npm i -g standard-version
//
// First Release
// This will tag a release without bumping the version bumpFiles
// npx standard-version --first-release --dry-run
//
// Cutting Releases
// After you cut a release, you can push the new git tag and cargo publish
// npx standard-version --dry-run
module.exports = () => {
    return {
        "bumpFiles": [],
        "packageFiles": [
            {
                "filename": "ver",
                "type": "plain-text"
            }
        ],
        "skip": {
            "tag": true
        }
    };
};
