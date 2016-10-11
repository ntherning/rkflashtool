#! /bin/sh

MAJOR=`grep MAJOR version.h | { read A B C; echo $C; }`
MINOR=`grep MINOR version.h | { read A B C; echo $C; }`

NAME=rkflashtool-$MAJOR.$MINOR
DIR=$NAME-src

SCRIPTS="rkparameters rkparametersblock rkmisc rkpad rkunsign"

rm -rf $DIR
mkdir $DIR

cp -a \
    Makefile \
    rkflashtool.c \
    rkcrc.c \
    rkcrc.h \
    rkunpack.c \
    version.h \
    $SCRIPTS \
    README \
    examples \
    $DIR

tar cvzf $DIR.tar.gz $DIR
tar cvjf $DIR.tar.bz2 $DIR
tar cvJf $DIR.tar.xz $DIR
zip -9r $DIR.zip $DIR

rm -rf $DIR

echo trying win32/win64 cross-builds...

rm -f rkflashtool.exe rkcrc.exe rkunpack.exe
make CROSSPREFIX=i686-w64-mingw32- || exit 1

zip -9r $NAME-win32-bin.zip rkflashtool.exe rkcrc.exe rkunpack.exe $SCRIPTS \
    examples

rm -f rkflashtool.exe rkcrc.exe rkunpack.exe
make CROSSPREFIX=x86_64-w64-mingw32- || exit 1

zip -9r $NAME-win64-bin.zip rkflashtool.exe rkcrc.exe rkunpack.exe $SCRIPTS \
    examples

rm -f rkflashtool.exe rkcrc.exe rkunpack.exe

echo trying macosx cross-builds...

rm -f rkflashtool rkcrc rkunpack
make CROSSPREFIX=i686-apple-darwin10- || exit 1

zip -9r $NAME-macosx-intel-bin.zip rkflashtool rkcrc rkunpack $SCRIPTS \
    examples

rm -f rkflashtool rkcrc rkunpack
make CROSSPREFIX=powerpc-apple-darwin10- || exit 1

zip -9r $NAME-macosx-powerpc-bin.zip rkflashtool rkcrc rkunpack $SCRIPTS \
    examples

rm -f rkflashtool rkcrc rkunpack

