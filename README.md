# Bufu-Sec Wiki

The wiki will contain all my notes and cheatsheets mostly related to Red Teaming. It uses the popular [doks](https://github.com/h-enk/doks) theme.

## Contributing

Feel free to contribute by making a pull request. You can also just use this repo as a template to create your own wiki and host it on Github Pages.

### Adding more Sections

I initially had some trouble setting up more than one `docs` section from the original theme and getting the search to work, but here are some references to help get you set up:

- [test-wiki commit 79c667f](https://github.com/xbufu/test-wiki/commit/8d4ff9b089a618e9319de1f3e986f87acd609417)
- [Discussion #173: How to create a new docs-like directory and menu](https://github.com/h-enk/doks/discussions/173)
- [Pull request by theme author: Update for second docs tree](https://github.com/atwriter/new_doks_site/pull/1/commits/40e6eae81a8748645525afadf21b1759ce5f2c77)
- [Discussion #543: Search function not working in second docs page](https://github.com/h-enk/doks/discussions/543)
- [Discussion #395: Getting search box to include blog posts](https://github.com/h-enk/doks/discussions/395)

---

<p align="center">
  <a href="https://getdoks.org/">
    <img alt="Doks" src="https://doks.netlify.app/doks.svg" width="60">
  </a>
</p>

<h2 align="center">
  Doks
</h1>

<h3 align="center">
  Modern Documentation Theme
</h3>

<p align="center">
  Doks is a Hugo theme for building secure, fast, and SEO-ready documentation websites, which you can easily update and customize.
</p>

<p align="center">
  <a href="https://github.com/h-enk/doks/blob/master/LICENSE">
    <img src="https://img.shields.io/github/license/h-enk/doks?style=flat-square" alt="GitHub">
  </a>
  <a href="https://github.com/h-enk/doks/releases">
    <img src="https://img.shields.io/github/v/release/h-enk/doks?include_prereleases&style=flat-square"alt="GitHub release (latest SemVer including pre-releases)">
  </a>
  <a href="https://www.npmjs.com/package/@hyas/doks">
    <img src="https://img.shields.io/npm/v/@hyas/doks?style=flat-square" alt="npm (scoped)">
  </a>
  <a href="https://github.com/h-enk/doks/actions?query=workflow%3A%22Hyas+CI%22">
    <img src="https://img.shields.io/github/workflow/status/h-enk/doks/Hyas%20CI/master?style=flat-square" alt="GitHub Workflow Status (branch)">
  </a>
  <a href="https://app.netlify.com/sites/doks/deploys">
    <img src="https://img.shields.io/netlify/8a1009d5-88ac-413e-96ef-3f928674a083?style=flat-square" alt="Netlify">
  </a>
</p>

![Doks — Modern Documentation Theme](https://raw.githubusercontent.com/h-enk/doks/master/images/tn.png)

## Demo

- [doks.netlify.app](https://doks.netlify.app/)

## Why Doks?

Nine main reasons why you should use Doks:

1. __Security aware__. Get A+ scores on [Mozilla Observatory](https://observatory.mozilla.org/analyze/doks.netlify.app) out of the box. Easily change the default Security Headers to suit your needs.

2. __Fast by default__. Get 100 scores on [Google Lighthouse](https://googlechrome.github.io/lighthouse/viewer/?gist=7731347bb8ce999eff7428a8e763b637) by default. Doks removes unused css, prefetches links, and lazy loads images.

3. __SEO-ready__. Use sensible defaults for structured data, open graph, and Twitter cards. Or easily change the SEO settings to your liking.

4. __Development tools__. Code with confidence. Check styles, scripts, and markdown for errors and fix automatically or manually.

5. __Bootstrap framework__. Build robust, flexible, and intuitive websites with Bootstrap 5. Easily customize your Doks site with the source Sass files.

6. __Netlify-ready__. Deploy to Netlify with sensible defaults. Easily use Netlify Functions, Netlify Redirects, and Netlify Headers.

7. __Full text search__. Search your Doks site with FlexSearch. Easily customize index settings and search options to your liking.

8. __Page layouts__. Build pages with a landing page, blog, or documentation layout. Add custom sections and components to suit your needs.

9. __Dark mode__. Switch to a low-light UI with the click of a button. Change colors with variables to match your branding.

### Other features

- __Multilingual and i18n__ support
- __Versioning__ documentation support
- __KaTeX__ math typesetting
- __Mermaid__ diagrams and visualization
- __highlight.js__ syntax highlighting

## Requirements

Doks uses npm to centralize dependency management, making it [easy to update](https://getdoks.org/docs/help/how-to-update/) resources, build tooling, plugins, and build scripts:

- Download and install [Node.js](https://nodejs.org/) (it includes npm) for your platform.

## Get started

Start a new Doks project in three steps:

### 1. Create a new site

Doks is available as a child theme, and a starter theme:

- Use the Doks child theme, if you do __not__ plan to customize a lot, and/or need future Doks updates.
- Use the Doks starter theme, if you plan to customize a lot, and/or do __not__ need future Doks updates.

Not quite sure? Use the Doks child theme.

#### Doks child theme

```bash
git clone https://github.com/h-enk/doks-child-theme.git my-doks-site && cd my-doks-site
```

#### Doks starter theme

```bash
git clone https://github.com/h-enk/doks.git my-doks-site && cd my-doks-site
```

### 2. Install dependencies

```bash
npm install
```

### 3. Start development server

```bash
npm run start
```

## Other commands

Doks comes with [commands](https://getdoks.org/docs/prologue/commands/) for common tasks.

## Documentation

- [Netlify](https://docs.netlify.com/)
- [Hugo](https://gohugo.io/documentation/)
- [Doks](https://getdoks.org/)

## Communities

- [Netlify Community](https://community.netlify.com/)
- [Hugo Forums](https://discourse.gohugo.io/)
- [Doks Discussions](https://github.com/h-enk/doks/discussions)

## Sponsors

Support this project by becoming a sponsor. Your logo will show up here with a link to your website.

[![OC sponsor 0](https://opencollective.com/doks/sponsor/0/avatar.svg)](https://opencollective.com/doks/sponsor/0/website)

## Backers

Support this project by becoming a backer. Your avatar will show up here.

[![Backers](https://opencollective.com/doks/backers.svg)](https://opencollective.com/doks)
