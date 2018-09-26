---
title: Migrate to Github Pages
tags:
  - Hexo
  - node.js
  - git
  - docker
  - NexT
categories:
  - note
date: 2017-05-29 23:31:00
---
So I finally decided to migrate my blog from [Logdown](http://logdown.com/) to [Github Pages](https://pages.github.com/). Took me about three days to get it done. Here I write down some notes to record the whole migration process.  

<!-- more -->  


# Installing Hexo
I chose [Hexo](https://hexo.io/zh-tw/) for my blog framework.

## Environment Setting
First I prepared a [docker image](https://github.com/bruce30262/docker-misc/blob/master/hexo-blog/Dockerfile) for my blogging environment. Then I created two repositories on github:  
* [bruce30262.github.io](https://github.com/bruce30262/bruce30262.github.io)
    * The actual content of the blog. Hexo will update this repo after the deployment.
* [bruce30262_blog](https://github.com/bruce30262/bruce30262_blog)
    * Content of the hexo framework ( markdown files, theme, config file...etc )
    * The docker container will mount this directory to the working directory, something like:
```
docker run -it --rm -p 4000:4000 -v [HOME_DIR]/bruce30262_blog:/app --name hexo-blog bruce30262/docker-misc:hexo-blog
```

Later inside the container we can just run the hexo command under the `/app` directory and start blogging.

## Hexo command
* `hexo init` : Initialize a hexo blog
* `hexo g(enerate)` : Generate the static site
* `hexo s(erver)` : Launch the blog at the local side ( for previewing )
* `hexo d(eploy)` : 
    * Deploy the blog to github pages.
    * To fully deploy the blog, use the `hexo g -d` or the `hexo d -g` command.
    * Before deploying the blog, we need to do some setting in `_config.yml`:
    ```
    deploy:
      type: git
      repo: https://github.com/bruce30262/bruce30262.github.io.git
    ```
    * Don't forget to install the **hexo-deployer-git** plugin

## Hexo plugin
To install the hexo plugin:

```
npm install [plugin_name] --save
```
* `hexo-deployer-git` : For deploying the blog to github
* `hexo-admin` : An admin interface for blogging
* `hexo-generator-sitemap` : For generating sitemap
* `hexo-generator-feed` : For generating atom.xml ( rss feed )


# Hexo theme
I chose the [NexT.Pisces](https://github.com/iissnan/hexo-theme-next) theme. Here's the [English](https://github.com/iissnan/hexo-theme-next/blob/master/README.en.md) and the [Chinese](http://theme-next.iissnan.com/getting-started.html) version of the theme's documentations.

To choose the Pisces scheme, modified the **theme's `_config.yml`**:
```
# Schemes
#scheme: Muse
#scheme: Mist
scheme: Pisces    <-- remove the comment
```

## Social link
In the **site's `_config.yml`**:
```
# Social 
social:
  Github: your github link
  Twitter: your twitter linmk
  Facebook: your facebook link
```
In the **theme's `_config.yml`**:
```
social_icons:
  enable: true
  # Icon Mappings.
  # KeyMapsToSocialItemKey: NameOfTheIconFromFontAwesome
  Github: github
  Twitter: twitter
  Facebook: facebook 
```

## View count & Visitor count
Enable the [**busuanzi** ( 不蒜子 )](http://busuanzi.ibruce.info/) feature.
In the **theme's `_config.yml`**:
```
# Show PV/UV of the website/page with busuanzi.
# Get more information on http://ibruce.info/2015/04/04/busuanzi/
busuanzi_count:
  # count values only if the other configs are false
  enable: true
  # custom uv span for the whole site
  site_uv: true
  site_uv_header: <i class="fa fa-user"></i>
  site_uv_footer: Total visitors
  # custom pv span for the whole site
  site_pv: true
  site_pv_header: <i class="fa fa-eye"></i>
  site_pv_footer: Total views
  # custom pv span for one page only
  page_pv: true
  page_pv_header: <i class="fa fa-eye"></i>
  page_pv_footer: views
```

## Share widget ( AddThis )
First login to the [AddThis](http://www.addthis.com/) website, and create a share widget. Then, in the **theme's `_config.yml`**:
```
# Share
#jiathis:
# Warning: JiaThis does not support https.
add_this_id: ra-XXXXXXXXXXXXX     <-- the pubid
```

## Migrate Disqus comment
First enable the disqus feature.

In the **site's `_config.yml`**:
```
disqus_shortname: old_disqus_shortname   <-- old site's disqus shortname
```

In the **theme's `_config.yml`**:
```
# Disqus
disqus:
  enable: true
  shortname: old_disqus_shortname   <-- old site's disqus shortname
  count: true    <-- display the comment count
```

Then, follow the step from the [disqus website](https://help.disqus.com/customer/portal/articles/912757-url-mapper), use the URL Mapper to migrate the disqus threads.

Also change the setting in the disqus account ( new website url, [add trust domains](https://help.disqus.com/customer/portal/articles/1261429-how-to-use-trusted-domains)...etc ). It will take a while for disqus to reset the whole thing.


# Migrate the blog
1. Export all the markdown files from Logdown.
2. Write some script to convert the posts' header ( author, tags, categories...etc ).
3. Move those files to the [bruce30262_blog](https://github.com/bruce30262/bruce30262_blog) repository.
4. Commit, push & deploy.


# Reference
* Github Pages + Hexo Tutorial
    * [link1](https://linghucong.js.org/2016/04/15/2016-04-15-hexo-github-pages-blog/) (Chinese)
    * [link2](https://xuanwo.org/2015/03/26/hexo-intor/) (Chinese)
* [Hexo blog development on Docker](http://phriscage.github.io/2016/01/18/Hexo-blog-development-on-Docker/)
* [Execute npm install hexo-cli -g promt ERR (root user)](https://github.com/hexojs/hexo/issues/2505)
* [Hexo sitemap](http://fionat.github.io/2016/04/02/sitemap/) (Chinese)
* [Hexo rss feed](http://hanhailong.com/2015/10/08/Hexo%E2%80%94%E6%AD%A3%E7%A1%AE%E6%B7%BB%E5%8A%A0RSS%E8%AE%A2%E9%98%85/) (Chinese)
* [Hexo NexT theme github page](https://github.com/iissnan/hexo-theme-next)
* [Add AddThis to Hexo-NexT-theme](https://github.com/iissnan/hexo-theme-next/pull/660) (Chinese)
* [Disqus Migration Tools](https://help.disqus.com/customer/portal/articles/286778-migration-tools)