# ECTester jekyll page

The Jekyll site of the [ECTester](https://github.com/crocs-muni/ECTester) project.

## Build

Ruby 2.1.0 or higher is required, for more info see [github docs](https://help.github.com/articles/setting-up-your-github-pages-site-locally-with-jekyll/).

Prepare:
```
gem install bundler
```

Install:
```
cd ECTester
git checkout gh-pages
bundle install
```

Build:
```
bundle exec jekyll build
```

## Import data

The page uses results in the YAML format, use `--format=yaml` or 
`-oyml:filename.extension` options with ECTester to output test results in YAML.

Putting the generated YAML file into `_results/<test-suite>/` will render it next
time Jekyll builds the site.

However, Jekyll ignores files ending with `.yml` while building pages out of
collections so a different extension is required, anything works. Only the
filename part without the extension is used to display the name of the tested device.