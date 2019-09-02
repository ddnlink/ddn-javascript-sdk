var options = require('./options');

module.exports = {

    init: function(nethash) {
        if (nethash) {
            options.set("nethash", nethash);
        }
    }

}