file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
  *.rc
)

list(SORT SRC_FILES)

ida_add_plugin(patch-finder SOURCES ${SRC_FILES})

momo_assign_source_group(${SRC_FILES})

set_property(GLOBAL PROPERTY VS_STARTUP_PROJECT patch-finder)
