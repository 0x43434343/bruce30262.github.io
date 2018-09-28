---
title: Some notes on migrating to Jekyll
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- Jekyll
- Ruby
- git
- docker
categories:
- note
toc: true
toc_label: Table of Contents
toc_sticky: true
---

Recently I've decided to migrate my blogging framework from [Hexo](https://hexo.io/zh-tw/) to [Jekyll](https://jekyllrb.com/). Here are some notes that I took for recording the migration process.

<!-- more -->

## Install Jekyll
Here I created a [Dockerfile](https://github.com/bruce30262/docker-misc/blob/master/jekyll-blog/Dockerfile) for my blogging environment. 

### From Hexo to Jekyll
Since I'm migrating to Jekyll, I had to clean my [bruce30262.github.io](https://github.com/bruce30262/bruce30262.github.io) repository and use Jekyll to build a new one. Here's what I did:
1. Remove all the contents inside the repo ( except the `.git` directory ).
2. `jekyll new myblog` to create a new blog.
3. Move all the files from `myblog` to the root directory, then remove `myblog`.
4. Add a new Gemfile.
5. `bundle install` to install the gems.

One of the problem I've encountered is that `jekyll-admin` was not installed even if I put it in my Gemfile. I had to use `gem install jekyll-admin` to fix the issue.

After that we can launch the blog with `bundle exec jekyll serve --host=0.0.0.0`, then go to `0.0.0.0:4000` to see if it work. To manage the blog just go to `0.0.0.0:4000/admin`.

### Working inside Docker
We can mount our working directory to the container and start working inside the docker with the following command:

```
IMG="some image name"
CTN="some container name"

docker run -e TERM --privileged --security-opt seccomp:unconfined -p 4000:4000 -v ~/bruce30262.github.io:/app --name=$(CTN) -it bruce30262/$(IMG) /bin/bash -c 'cd /app && bundle exec jekyll serve --host 0.0.0.0'
```

The Jekyll docker container uses user `jekyll` ( uid = 1000 ) to configure the blog, so it'll be the best if your own uid on the linux host is also 1000, making you able to work both outside/inside the docker ( since you have the same uid, working as jekyll inside the docker = working as yourself on the linux host ) without having the permission problem.

## Install the theme
I'm using [Minimal Mistakes](https://mmistakes.github.io/minimal-mistakes/) as my theme. I like its dark theme, also it's well documented :).

To use the theme on github page you'll have to use the `remote-theme` in `_config.yml`:

```
remote_theme: bruce30262/minimal-mistakes
```

After that you can just follow the step in the [documentation](https://mmistakes.github.io/minimal-mistakes/docs/configuration/) to configure all the thing. The [offcial config setting](https://github.com/mmistakes/minimal-mistakes/blob/master/docs/_config.yml) is also worth reading. 

### Customizing the theme

I've [forked the theme repo](https://github.com/bruce30262/minimal-mistakes) so I can apply my own customized theme to the blog.

For example I don't like the syntax highlighting in the dark theme and preferred the default one, so I follow the steps mentioned in [this issue](https://github.com/mmistakes/minimal-mistakes/issues/1458) and modified the content of `assets/css/main.scss`:
```css
@import "minimal-mistakes/skins/{{ site.minimal_mistakes_skin | default: 'default' }}"; // skin

/* default syntax highlighting (base16) */
$base00: #263238 !important; 
$base01: #2e3c43 !important;
$base02: #314549 !important;
$base03: #546e7a !important;
$base04: #b2ccd6 !important;
$base05: #eeffff !important;
$base06: #eeffff !important;
$base07: #ffffff !important;
$base08: #f07178 !important;
$base09: #f78c6c !important;
$base0a: #ffcb6b !important;
$base0b: #c3e88d !important;
$base0c: #89ddff !important;
$base0d: #82aaff !important;
$base0e: #c792ea !important;
$base0f: #ff5370 !important;

@import "minimal-mistakes"; // main partials
```

For the color code you can just check the [documentation](https://mmistakes.github.io/minimal-mistakes/docs/stylesheets/#colors).

### Migrating Disqus comment

Migrating Disqus comment to a new blog is always a troublesome :/

To enable the disqus feature use the `comments` setting in `_config.yml`

```
comments:
  provider: "disqus"
  disqus:
    shortname: (disqus_shortname)
```

Also make sure to set the `url` key in `_config.yml` if you're using the github page, or else the [disqus_config function](https://github.com/bruce30262/bruce30262.github.io/blob/master/_site/Learning-browser-exploitation-via-33C3-CTF-feuerfuchs-challenge/index.html#L863) will not work.

After that, follow the steps from the [disqus website](https://help.disqus.com/import-export-and-syncing/url-mapper), use the URL Mapper to migrate the threads.

## Migrate the blog posts
Simply copy the markdown files to the `_posts` folder. Remember to rename those files that don't fit the Jekyll naming convention ( `yyyy-mm-dd-title.md`). Also in order to show the `autho_profile` ( left side of the page ), you'll have to remove the `author` metadata field in each post.

After that just fix some format ( especially the code hightlighting ) and  we're all good.

## Reference
* [Github pages + Minimal-Mistakes + Disqus](https://www.cnblogs.com/StartoverX/p/8996725.html) (Chinese)
* [Minimal Mistakes](https://github.com/mmistakes/minimal-mistakes)
* [Adding Sitemap To Jekyll Blog](https://blog.webjeda.com/jekyll-sitemap/)
