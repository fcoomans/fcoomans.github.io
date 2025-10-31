# Portfolio Website

This is my personal portfolio website hosted on GitHub Pages, built with Jekyll using the Minimal Mistakes theme. 

It features cybersecurity write-ups and reports, a CV, and a contact form integrated with Formspree. 

The site is based on the [Minimal Mistakes GitHub Pages starter template](https://github.com/mmistakes/mm-github-pages-starter), with modifications such as removing blog posts to focus on portfolio content (posts may be added back later for expanded sharing).

## Technologies Used

- Jekyll (for static site generation)
- Minimal Mistakes Jekyll theme
- HTML
- CSS (including _sass for custom styling)
- JavaScript
- Formspree (for contact form)

## Local Development

For local preview and development:

1. Ensure Ruby and Bundler are installed. Also, modify variables on Linux:
```
export PATH="$HOME/.local/share/gem/ruby/3.3.0/bin:$PATH"
export GEM_HOME="$HOME/.local/share/gem/ruby/3.3.0"
```
2. Clone the repository: `git clone https://github.com/fcoomans/fcoomans.github.io.git`
3. Navigate to the project directory: `cd fcoomans.github.io`
4. Install dependencies: `bundle install`
5. Run the local server: `bundle exec jekyll serve`
6. Access the site at http://localhost:4000 in a web browser.

This repository is primarily a personal portfolio site and not intended for general cloning or forking by others. 
However, if you're interested in viewing the implementation details, such as front matter, `_sass` CSS, etc., feel free to explore the code.

## Live Site

- URL: https://fcoomans.github.io
