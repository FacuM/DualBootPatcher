if(ANDROID)
    set(FREETYPE_INCLUDE_DIR_ft2build
        ${THIRD_PARTY_FREETYPE2_DIR}/${ANDROID_ABI}/include)
    set(FREETYPE_INCLUDE_DIR_freetype2
        ${FREETYPE_INCLUDE_DIR_ft2build}/freetype)
    set(FREETYPE_LIBRARY
        ${THIRD_PARTY_FREETYPE2_DIR}/${ANDROID_ABI}/lib/libft2.a)
endif()

find_package(Freetype REQUIRED)

set(MBP_FREETYPE2_INCLUDES ${FREETYPE_INCLUDE_DIRS})
set(MBP_FREETYPE2_LIBRARIES ${FREETYPE_LIBRARIES})
