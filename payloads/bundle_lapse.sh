#!/bin/bash

cat 1_lapse_prepare_1.js 2_lapse_prepare_2.js 3_lapse_nf.js  > lapse.js
node --check lapse.js
echo "lapse bundled!"
