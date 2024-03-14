#include "gsgpu.h"
#include "gsgpu_display.h"
#include <drm/gsgpu_drm.h>
#include <linux/dma-buf.h>
#include <linux/dma-fence-array.h>
#include <linux/pci-p2pdma.h>
#include <linux/pm_runtime.h>

MODULE_IMPORT_NS(DMA_BUF);

/**
 * gsgpu_dma_buf_pin - &dma_buf_ops.pin implementation
 *
 * @attach: attachment to pin down
 *
 * Pin the BO which is backing the DMA-buf so that it can't move any more.
 */
static int gsgpu_dma_buf_pin(struct dma_buf_attachment *attach)
{
	struct drm_gem_object *obj = attach->dmabuf->priv;
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(obj);

	/* pin buffer into GTT */
	return gsgpu_bo_pin(bo, GSGPU_GEM_DOMAIN_GTT);
}

/**
 * gsgpu_dma_buf_unpin - &dma_buf_ops.unpin implementation
 *
 * @attach: attachment to unpin
 *
 * Unpin a previously pinned BO to make it movable again.
 */
static void gsgpu_dma_buf_unpin(struct dma_buf_attachment *attach)
{
	struct drm_gem_object *obj = attach->dmabuf->priv;
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(obj);

	gsgpu_bo_unpin(bo);
}

/**
 * gsgpu_dma_buf_map - &dma_buf_ops.map_dma_buf implementation
 * @attach: DMA-buf attachment
 * @dir: DMA direction
 *
 * Makes sure that the shared DMA buffer can be accessed by the target device.
 * For now, simply pins it to the GTT domain, where it should be accessible by
 * all DMA devices.
 *
 * Returns:
 * sg_table filled with the DMA addresses to use or ERR_PRT with negative error
 * code.
 */
static struct sg_table *gsgpu_dma_buf_map(struct dma_buf_attachment *attach,
					  enum dma_data_direction dir)
{
	struct dma_buf *dma_buf = attach->dmabuf;
	struct drm_gem_object *obj = dma_buf->priv;
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(obj);
	struct gsgpu_device *adev = gsgpu_ttm_adev(bo->tbo.bdev);
	struct sg_table *sgt;
	long r;

	if (!bo->tbo.pin_count) {
		/* move buffer into GTT */
		struct ttm_operation_ctx ctx = { false, false };
		gsgpu_bo_placement_from_domain(bo, GSGPU_GEM_DOMAIN_GTT);
		r = ttm_bo_validate(&bo->tbo, &bo->placement, &ctx);
		if (r)
			return ERR_PTR(r);
	} else if (!(gsgpu_mem_type_to_domain(bo->tbo.resource->mem_type) &
		     GSGPU_GEM_DOMAIN_GTT)) {
		return ERR_PTR(-EBUSY);
	}

	switch (bo->tbo.resource->mem_type) {
	case TTM_PL_TT:
		sgt = drm_prime_pages_to_sg(obj->dev,
					    bo->tbo.ttm->pages,
					    bo->tbo.ttm->num_pages);
		if (IS_ERR(sgt))
			return sgt;

		if (dma_map_sgtable(attach->dev, sgt, dir,
				    DMA_ATTR_SKIP_CPU_SYNC))
			goto error_free;
		break;

	case TTM_PL_VRAM:
		r = gsgpu_vram_mgr_alloc_sgt(adev, bo->tbo.resource, 0,
					     bo->tbo.base.size, attach->dev,
					     dir, &sgt);
		if (r)
			return ERR_PTR(r);
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	return sgt;

error_free:
	sg_free_table(sgt);
	kfree(sgt);
	return ERR_PTR(-EBUSY);
}

/**
 * gsgpu_dma_buf_unmap - &dma_buf_ops.unmap_dma_buf implementation
 * @attach: DMA-buf attachment
 * @sgt: sg_table to unmap
 * @dir: DMA direction
 *
 * This is called when a shared DMA buffer no longer needs to be accessible by
 * another device. For now, simply unpins the buffer from GTT.
 */
static void gsgpu_dma_buf_unmap(struct dma_buf_attachment *attach,
				struct sg_table *sgt,
				enum dma_data_direction dir)
{
	if (sgt->sgl->page_link) {
		dma_unmap_sgtable(attach->dev, sgt, dir, 0);
		sg_free_table(sgt);
		kfree(sgt);
	} else {
		gsgpu_vram_mgr_free_sgt(attach->dev, dir, sgt);
	}
}

/**
 * gsgpu_dma_buf_attach - &dma_buf_ops.attach implementation
 *
 * @dmabuf: DMA-buf where we attach to
 * @attach: attachment to add
 *
 * Add the attachment as user to the exported DMA-buf.
 */
static int gsgpu_dma_buf_attach(struct dma_buf *dmabuf,
				struct dma_buf_attachment *attach)
{
	struct drm_gem_object *obj = dmabuf->priv;
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(obj);
	struct gsgpu_device *adev = gsgpu_ttm_adev(bo->tbo.bdev);
	int r;

	if (pci_p2pdma_distance(adev->pdev, attach->dev, false) < 0)
		attach->peer2peer = false;

	r = pm_runtime_get_sync(adev_to_drm(adev)->dev);
	if (r < 0)
		goto out;

	return 0;

out:
	pm_runtime_put_autosuspend(adev_to_drm(adev)->dev);
	return r;
}

/**
 * gsgpu_dma_buf_detach - &dma_buf_ops.detach implementation
 *
 * @dmabuf: DMA-buf where we remove the attachment from
 * @attach: the attachment to remove
 *
 * Called when an attachment is removed from the DMA-buf.
 */
static void gsgpu_dma_buf_detach(struct dma_buf *dmabuf,
				 struct dma_buf_attachment *attach)
{
	struct drm_gem_object *obj = dmabuf->priv;
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(obj);
	struct gsgpu_device *adev = gsgpu_ttm_adev(bo->tbo.bdev);

	pm_runtime_mark_last_busy(adev_to_drm(adev)->dev);
	pm_runtime_put_autosuspend(adev_to_drm(adev)->dev);
}

/**
 * gsgpu_dma_buf_begin_cpu_access - &dma_buf_ops.begin_cpu_access implementation
 * @dma_buf: Shared DMA buffer
 * @direction: Direction of DMA transfer
 *
 * This is called before CPU access to the shared DMA buffer's memory. If it's
 * a read access, the buffer is moved to the GTT domain if possible, for optimal
 * CPU read performance.
 *
 * Returns:
 * 0 on success or a negative error code on failure.
 */
static int gsgpu_dma_buf_begin_cpu_access(struct dma_buf *dma_buf,
					  enum dma_data_direction direction)
{
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(dma_buf->priv);
	struct gsgpu_device *adev = gsgpu_ttm_adev(bo->tbo.bdev);
	struct ttm_operation_ctx ctx = { true, false };
	u32 domain = gsgpu_display_supported_domains(adev);
	int ret;
	bool reads = (direction == DMA_BIDIRECTIONAL ||
		      direction == DMA_FROM_DEVICE);

	if (!reads || !(domain & GSGPU_GEM_DOMAIN_GTT))
		return 0;

	/* move to gtt */
	ret = gsgpu_bo_reserve(bo, false);
	if (unlikely(ret != 0))
		return ret;

	if (!bo->tbo.pin_count && (bo->allowed_domains & GSGPU_GEM_DOMAIN_GTT)) {
		gsgpu_bo_placement_from_domain(bo, GSGPU_GEM_DOMAIN_GTT);
		ret = ttm_bo_validate(&bo->tbo, &bo->placement, &ctx);
	}

	gsgpu_bo_unreserve(bo);
	return ret;
}

const struct dma_buf_ops gsgpu_dmabuf_ops = {
	.attach = gsgpu_dma_buf_attach,
	.detach = gsgpu_dma_buf_detach,
	.pin = gsgpu_dma_buf_pin,
	.unpin = gsgpu_dma_buf_unpin,
	.map_dma_buf = gsgpu_dma_buf_map,
	.unmap_dma_buf = gsgpu_dma_buf_unmap,
	.release = drm_gem_dmabuf_release,
	.begin_cpu_access = gsgpu_dma_buf_begin_cpu_access,
	.mmap = drm_gem_dmabuf_mmap,
	.vmap = drm_gem_dmabuf_vmap,
	.vunmap = drm_gem_dmabuf_vunmap,
};

/**
 * gsgpu_gem_prime_export - &drm_driver.gem_prime_export implementation
 * @gobj: GEM BO
 * @flags: Flags such as DRM_CLOEXEC and DRM_RDWR.
 *
 * The main work is done by the &drm_gem_prime_export helper.
 *
 * Returns:
 * Shared DMA buffer representing the GEM BO from the given device.
 */
struct dma_buf *gsgpu_gem_prime_export(struct drm_gem_object *gobj,
				       int flags)
{
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(gobj);
	struct dma_buf *buf;

	if (gsgpu_ttm_tt_get_usermm(bo->tbo.ttm) ||
	    bo->flags & GSGPU_GEM_CREATE_VM_ALWAYS_VALID)
		return ERR_PTR(-EPERM);

	buf = drm_gem_prime_export(gobj, flags);
	if (!IS_ERR(buf))
		buf->ops = &gsgpu_dmabuf_ops;

	return buf;
}

/**
 * gsgpu_dma_buf_create_obj - create BO for DMA-buf import
 *
 * @dev: DRM device
 * @dma_buf: DMA-buf
 *
 * Creates an empty SG BO for DMA-buf import.
 *
 * Returns:
 * A new GEM BO of the given DRM device, representing the memory
 * described by the given DMA-buf attachment and scatter/gather table.
 */
static struct drm_gem_object *
gsgpu_dma_buf_create_obj(struct drm_device *dev, struct dma_buf *dma_buf)
{
	struct dma_resv *resv = dma_buf->resv;
	struct gsgpu_device *adev = drm_to_adev(dev);
	uint64_t flags = 0;

	dma_resv_lock(resv, NULL);

	if (dma_buf->ops == &gsgpu_dmabuf_ops) {
		struct gsgpu_bo *other = gem_to_gsgpu_bo(dma_buf->priv);

		flags = other->flags & GSGPU_GEM_CREATE_CPU_GTT_USWC;
	}

	struct drm_gem_object *gobj;
	int ret = gsgpu_gem_object_create(adev, dma_buf->size, PAGE_SIZE,
					  GSGPU_GEM_DOMAIN_CPU, flags,
					  ttm_bo_type_sg, resv, &gobj);
	if (ret)
		goto out;

	struct gsgpu_bo *bo;
	bo = gem_to_gsgpu_bo(gobj);
	bo->allowed_domains = GSGPU_GEM_DOMAIN_GTT;
	bo->preferred_domains = GSGPU_GEM_DOMAIN_GTT;

out:
	dma_resv_unlock(resv);
	return ret ? ERR_PTR(ret) : gobj;
}

/**
 * gsgpu_dma_buf_move_notify - &attach.move_notify implementation
 *
 * @attach: the DMA-buf attachment
 *
 * Invalidate the DMA-buf attachment, making sure that the we re-create the
 * mapping before the next use.
 */
static void gsgpu_dma_buf_move_notify(struct dma_buf_attachment *attach)
{
	struct drm_gem_object *obj = attach->importer_priv;
	struct ww_acquire_ctx *ticket = dma_resv_locking_ctx(obj->resv);
	struct gsgpu_bo *bo = gem_to_gsgpu_bo(obj);
	struct gsgpu_device *adev = gsgpu_ttm_adev(bo->tbo.bdev);
	struct ttm_operation_ctx ctx = { false, false };
	struct ttm_placement placement = {};
	int r;

	if (!bo->tbo.resource || bo->tbo.resource->mem_type == TTM_PL_SYSTEM)
		return;

	r = ttm_bo_validate(&bo->tbo, &placement, &ctx);
	if (r) {
		DRM_ERROR("Failed to invalidate DMA-buf import (%d))\n", r);
		return;
	}

	struct gsgpu_bo_va *bo_va;
	list_for_each_entry(bo_va, &bo->va, base.bo_list) {
		struct gsgpu_vm *vm = bo_va->base.vm;
		struct dma_resv *resv = vm->root.base.bo->tbo.base.resv;

		if (ticket) {
			/* When we get an error here it means that somebody
			 * else is holding the VM lock and updating page tables
			 * So we can just continue here.
			 */
			r = dma_resv_lock(resv, ticket);
			if (r)
				continue;

		} else {
			/* TODO: This is more problematic and we actually need
			 * to allow page tables updates without holding the
			 * lock.
			 */
			if (!dma_resv_trylock(resv))
				continue;
		}

		r = gsgpu_vm_clear_freed(adev, vm, NULL);
		if (!r)
			r = gsgpu_vm_handle_moved(adev, vm);

		if (r && r != -EBUSY)
			DRM_ERROR("Failed to invalidate VM page tables (%d))\n",
				  r);

		dma_resv_unlock(resv);
	}
}

static const struct dma_buf_attach_ops gsgpu_dma_buf_attach_ops = {
	.allow_peer2peer = false,
	.move_notify = gsgpu_dma_buf_move_notify
};

/**
 * gsgpu_gem_prime_import - &drm_driver.gem_prime_import implementation
 * @dev: DRM device
 * @dma_buf: Shared DMA buffer
 *
 * Import a dma_buf into a the driver and potentially create a new GEM object.
 *
 * Returns:
 * GEM BO representing the shared DMA buffer for the given device.
 */
struct drm_gem_object *gsgpu_gem_prime_import(struct drm_device *dev,
					      struct dma_buf *dma_buf)
{
	struct dma_buf_attachment *attach;
	struct drm_gem_object *obj;

	if (dma_buf->ops == &gsgpu_dmabuf_ops) {
		obj = dma_buf->priv;
		if (obj->dev == dev) {
			/*
			 * Importing dmabuf exported from out own gem increases
			 * refcount on gem itself instead of f_count of dmabuf.
			 */
			drm_gem_object_get(obj);
			return obj;
		}
	}

	obj = gsgpu_dma_buf_create_obj(dev, dma_buf);
	if (IS_ERR(obj))
		return obj;

	attach = dma_buf_dynamic_attach(dma_buf, dev->dev,
					&gsgpu_dma_buf_attach_ops, obj);
	if (IS_ERR(attach)) {
		drm_gem_object_put(obj);
		return ERR_CAST(attach);
	}

	get_dma_buf(dma_buf);
	obj->import_attach = attach;
	return obj;
}
