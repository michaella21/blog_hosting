# Blog_Hosting 
### with Python 2.7/ Flask/ SQLAlchemy/ SQLite
This repository contains files to create a blog hosting app. In this app, user can write own post as well as read someone else's recent and/or popular posts. By logging in with user's facebook or gmail account, user can also add a comment to the other users' posts or 'Like' it. User can attach an image file to own post as well as to its own profile picture.

This app also provides the JSON endpoint. For the front(main) page('/' or '/main'), user's blog page('/blog/<blog_id>'), and each post page('/viewpost/<post_id>'), total category(/categorie) and each category(/categories/<category>)add '/JSON' at the end of each url should provide the JSON format of the same data included in HTML endpoint. 

## Requirements
To use the file included in this repository, Linux based virtual machine is required. You can download [VBox](https://www.virtualbox.org/wiki/Downloads) and [vagrant](https://www.vagrantup.com/downloads.html) from each link and install them as directed. Once virtual machine is installed, you can download [the configuration file](https://github.com/udacity/fullstack-nanodegree-vm/blob/master/vagrant/Vagrantfile). You can bring the virtual machine back online (with `vagrant up`) and log into it with `vagrant ssh`.

## Running the script
Sample data was populated by database_populate.py and saved in 'bloghost.db' While you log into virtual machine, simply run the scripy by
```
python views.py
```
It should locally run on http://localhost:5000 
