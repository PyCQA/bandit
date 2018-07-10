from django.core.files.images import get_image_dimensions

(width, height) = get_image_dimensions('pic_folder/no-img.tiff')
